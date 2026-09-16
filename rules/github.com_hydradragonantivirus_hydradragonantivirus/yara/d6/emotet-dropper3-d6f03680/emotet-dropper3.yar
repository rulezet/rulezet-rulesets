rule emotet_dropper3 {
  meta:
    description = "03-01-19 - file emotet-dropper3.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-03-01"
    hash1       = "1673f455fb491289c298b4ff52a76e979da0531e93d65b93c922a80190f247ca"

  strings:
    $s1  = "$sp6345e2 = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';" fullword ascii
    $s2  = "private $contentName_ = 'iMDbapCVgUb.exe';" fullword ascii
    $s3  = "echo $sp58859d->execute();" fullword ascii
    $s4  = "'(?:Apple-)?(?:iPhone|iPad|iPod)(?:.*Mac OS X.*Version/(\\\\d+\\\\.\\\\d+)|;" fullword ascii
    $s5  = "header('Content-Type: ' . $this->contentType_);" fullword ascii
    $s6  = "header('Content-Disposition: attachment;" fullword ascii
    $s7  = ".*((?:Debian|Knoppix|Mint|Ubuntu|Kubuntu|Xubuntu|Lubuntu|Fedora|Red Hat|Mandriva|Gentoo|Sabayon|Slackware|SUSE|CentOS|BackTrack" fullword ascii
    $s8  = "'(?:(?:Orca-)?Android|Adr)[ /](?:[a-z]+ )?(\\\\d+[\\\\.\\\\d]+)'," fullword ascii
    $s9  = "private $content_ = '[omitted due to size]';" fullword ascii
    $s10 = "$sp7c7c2a = json_decode(fread($spdfc158, $spe8c644) , true);" fullword ascii
    $s11 = "ini_set('max_execution_time', 0);" fullword ascii
    $s12 = "?: Enterprise)? Linux)?(?:[ /\\\\-](\\\\d+[\\\\.\\\\d]+))?'," fullword ascii
    $s13 = "'VectorLinux(?: package)?(?:[ /\\\\-](\\\\d+[\\\\.\\\\d]+))?'," fullword ascii
    $s14 = "'CYGWIN_NT-5.2|Windows NT 5.2|Windows Server 2003 / XP x64'," fullword ascii
    $s15 = "'Darwin|Macintosh|Mac_PowerPC|PPC|Mac PowerPC|iMac|MacBook'" fullword ascii
    $s16 = "header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');" fullword ascii
    $s17 = "return base64_decode($this->content_);" fullword ascii
    $s18 = "'Arch ?Linux(?:[ /\\\\-](\\\\d+[\\\\.\\\\d]+))?'," fullword ascii
    $s19 = "header('Expires: Tue, 01 Jan 1970 00:00:00 GMT');" fullword ascii
    $s20 = "private $contentType_ = 'application/octet-stream';" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 10KB and
      (8 of them)
    ) or (all of them)
}