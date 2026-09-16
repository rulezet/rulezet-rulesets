rule Obfs_behavior_wmi {
    meta:
        description = "detection for JS Loader focusing on WMI/ADSI discovery and XOR loops"
        author = "k3rnelcallz"
        reference = "malwarebazaar"
        sha = "2e5934e38666e63c23f5906e5175a1bf5c230972cb57bb8c07dab0630921fa43"

    strings:
        
        $xor_math = { 2A [1-10] 2B [1-10] 26 20 32 35 35 } 

        
        $obj1 = "Schedule.Service"
        $obj2 = "Win32_Process"
        $obj3 = "ADODB.Stream"
        $obj4 = "OpenDSObject"          
        
        $sid_admin = "-512"              $stealth = "ShowWindow = 0"
        $rand_seed = "Math.random() * 900000"

    condition:
        (filesize < 300KB) and ($xor_math and 2 of ($obj*, $sid_admin, $stealth, $rand_seed))
}