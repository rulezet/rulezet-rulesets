rule CN_Honker_Perl_serv_U_RID2F2D : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file Perl-serv-U.pl"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:46:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$dir = 'C:\\\\WINNT\\\\System32\\\\';" fullword ascii
      $s2 = "$sock = IO::Socket::INET->new(\"127.0.0.1:$adminport\") || die \"fail\";" fullword ascii
   condition: 
      filesize < 8KB and all of them
}