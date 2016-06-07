#!/usr/bin/env python
import subprocess
import shlex
import sys
import time

class StatisticsParser(object):
    '''
    *hashcat with "--status --quiet --status-automat":
    STATUS\t2\tSPEED\t67108864\t13.601808\t67108864\t13.606057\tCURKU\t1835008\tPROGRESS\t786710921216\t7446353252589\tRECHASH\t0\t23980\tRECSALT\t0\t1\tTEMP\t85\t78\t\n
    '''

    def __init__(self, stats):
        self.stats = stats.split()

    def _findvars(self, start, end):
        start = self.stats.index(start) + 1
        if end == None:
                return self.stats[start:]
        end =  self.stats.index(end)
        return self.stats[start:end]

    def status(self):
        return int(self._findvars('STATUS', 'SPEED')[0])

    def speed(self):
        return self._findvars('SPEED', 'CURKU')

    def current_keyspace_unit(self):
        return int(self._findvars('CURKU', 'PROGRESS')[0])

    def progress(self):
        return self._findvars('PROGRESS', 'RECHASH')

    def recovered_hashes(self):
        return self._findvars('RECHASH', 'RECSALT')

    def recovered_salts(self):
        return self._findvars('RECSALT', 'TEMP')

    def temperatures(self):
        return self._findvars('TEMP', None)

    def highest_temperature(self):
        return int(max(self.temperatures()))

    def gpus(self):
        return int(len(self.speed())) / 2


class HashcatInteractions(object):

    def __init__(self, hashcat_process):
        self.process = hashcat_process
        self.check_start = ''
        # wait hashcat to start
        while 'Device' not in self.check_start:
            #self.process.stdin.write('s')
            self.check_start = self.process.stdout.readline()
            time.sleep(0.5)

    def _search_pattern(self, pattern):
        line = self.process.stdout.readline()
        while True:
            if pattern in line:
                return line
            else:
                line = self.process.stdout.readline()
        
        return

    def stats(self):
        self.process.stdin.write('s')
        return self._search_pattern('STATUS')

    def pause(self):
        self.process.stdin.write('p')
        if 'Paused' in self._search_pattern('Paused'):
            return True

        return False

    def resume(self):
        self.process.stdin.write('r')
        if 'Resumed' in self._search_pattern('Resumed'):
            return True

        return False

    def quit(self):
        return self.process.stdin.write('q')


def hashcat_run(command, min_threshold, max_threshold, stats_timer):
    # define status values
    status = {
                0: "",
                1: "",
                2: "running",
                3: "paused",
                4: "exhausted",
                5: "cracked",
                6: "",
                7: "",
    }

    paused = False
    process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    hashcat = HashcatInteractions(process)
    
    # Poll process for new output until finished
    while True:
        if process.poll() is not None:
            break
        try:
            stats = StatisticsParser(hashcat.stats())
            print('status: %s' % stats.status())
            print('speed: %s' % stats.speed())
            print('current_keyspace_unit: %s' % stats.current_keyspace_unit())
            print('progress: %s' % stats.progress())
            print('recovered_hashes: %s' % stats.recovered_hashes())
            print('recovered_salts: %s' % stats.recovered_salts())
            print('temp: %s' % stats.temperatures())
            print('highest_temp: %s' % stats.highest_temperature())
            print('gpus: %s' % stats.gpus())
            print('paused: %s' % paused)

            # cracking only under speficic temperature threshold
            highest = stats.highest_temperature()

            # check highest temp vs temp threshold
            if highest >= max_threshold and not paused:
                print("temp %s reach temp threshold %s, pausing..." % (highest, max_threshold))
                if hashcat.pause():
                    paused = True
            
            # are we cooler than before?
            if highest <= min_threshold and paused:
                print("temp %s under temp threshold %s, resuming..." % (highest, min_threshold))
                if hashcat.resume():
                    paused = False

        except KeyboardInterrupt, e:
            print "keyboard interrupt detected, quiting..."
            hashcat.quit()
            sys.exit(1)
        
        time.sleep(stats_timer)

    return


if __name__ == '__main__':
    command = "/c/tools/oclHashcat-2.01/oclHashcat64.bin -a 3 -m 0 --status-automat --remove --increment --increment-min=7 --outfile=hashes.cracked /c/jobs/hashkiller/5918/hashes.md5 -1 ?u?d?s ?1?1?1?1?1?1?1?1?1?1"
    #command = "/c/tools/oclHashcat-2.01/oclHashcat64.bin -m 500 --status-automat /c/tools/oclHashcat-2.01/example500.hash /c/tools/oclHashcat-2.01/example.dict"
    #command = "/c/tools/oclHashcat-2.01/oclHashcat64.bin --status-automat -t 32 -a 7 /c/tools/oclHashcat-2.01/example0.hash ?a?a?a?a /c/tools/oclHashcat-2.01/example.dict"

    temp_max_threshold = 88
    temp_min_threshold = 55
    stats_timer = 3
    hashcat_run(command, temp_min_threshold, temp_max_threshold, stats_timer)
