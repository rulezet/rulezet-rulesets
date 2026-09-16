rule CRAIU_Susp_Ios_Shutdown {
  meta:
    description = "Detect shutdown.log files from sysdiags with suspicious entries"
    author      = "Costin G. Raiu, Art of Noh, craiu@noh.ro"
    id          = "08aa1fb9-7af0-515a-91a8-09ed35e48155"
    date        = "2023-12-28"
    modified    = "2024-03-05"
    reference   = "https://securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734/"
    source_url  = "https://github.com/craiu/yararules/blob/68bc7e129467d2c027f06918f28c3196e5c684a1/files/susp_ios_shutdown.yara#L2-L25"
    license_url = "https://github.com/craiu/yararules/blob/68bc7e129467d2c027f06918f28c3196e5c684a1/LICENSE"
    logic_hash  = "936101f2dddb73f6dda41be47d775199c458aa4fecdcf348ed479da620343ea1"
    score       = 65
    quality     = 85
    tags        = ""
    version     = "1.0"
    tlp         = "TLP:CLEAR"

  strings:
    $a1 = "these clients are still here:"
    $b1 = "/private/var/db/"
    $b2 = "/private/var/tmp/"
    $c1 = "After "

  condition:
    ($c1 at 0) and $a1 and (any of ($b*))
}