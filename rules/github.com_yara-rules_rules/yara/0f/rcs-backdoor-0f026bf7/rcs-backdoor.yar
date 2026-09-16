rule RCS_Backdoor
{
    
    meta:
        description = "Hacking Team RCS Backdoor"
        author = "botherder https://github.com/botherder"

    strings:
        $filter1 = "$debug3"
        $filter2 = "$log2"
        $filter3 = "error2"
        $debug1 = /\- (C)hecking components/ wide ascii
        $debug2 = /\- (A)ctivating hiding system/ wide ascii
        $debug3 = /(f)ully operational/ wide ascii
        $log1 = /\- Browser activity \(FF\)/ wide ascii
        $log2 = /\- Browser activity \(IE\)/ wide ascii
                                $error1 = /\[Unable to deploy\]/ wide ascii
        $error2 = /\[The system is already monitored\]/ wide ascii

    condition:
        (2 of ($debug*) or 2 of ($log*) or all of ($error*)) and not any of ($filter*)
}