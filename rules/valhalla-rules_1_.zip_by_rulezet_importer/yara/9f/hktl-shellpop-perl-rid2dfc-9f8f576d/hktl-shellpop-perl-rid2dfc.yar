rule HKTL_shellpop_Perl_RID2DFC : DEMO HKTL SCRIPT {
   meta:
      description = "Detects Shellpop Perl script"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 10:55:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "32c3e287969398a070adaad9b819ee9228174c9cb318d230331d33cda51314eb"
      tags = "DEMO, HKTL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "perl -e 'use IO::Socket::INET;$|=1;my ($s,$r);" ascii
      $ = ";STDIN->fdopen(\\$c,r);$~->fdopen(\\$c,w);s" ascii
   condition: 
      filesize < 2KB and 1 of them
}