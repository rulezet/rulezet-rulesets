rule M_Hunting_Dropper_THINSPOOL_1 {
  meta:
    author = "Mandiant"
    description = "This rule detects THINSPOOL, a dropper that installs the LIGHTWIRE web shell onto a Pulse Secure system."
    md5 = "677c1aa6e2503b56fe13e1568a814754"
    reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
    date = "2024-01-11"
    score = 75
    id = "dd340f72-0a2c-5b66-9e31-1c0f20cd842f"
  strings:
    $s1 = "/tmp/qactg/" ascii
    $s2 = "echo '/home/config/dscommands'" ascii
    $s3 = "echo '/home/perl/DSLogConfig.pm'" ascii
    $s4 = "ADM20447" ascii
  condition:
    filesize < 10KB
    and all of them
}