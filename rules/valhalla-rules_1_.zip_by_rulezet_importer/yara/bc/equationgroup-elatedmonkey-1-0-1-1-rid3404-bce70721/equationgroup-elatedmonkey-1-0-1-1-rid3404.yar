rule EquationGroup_elatedmonkey_1_0_1_1_RID3404 : APT DEMO G0020 SCRIPT {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file elatedmonkey.1.0.1.1.sh"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 15:12:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-08-18"
      hash1 = "bf7a9dce326604f0681ca9f7f1c24524543b5be8b6fcc1ba427b18e2a4ff9090"
      tags = "APT, DEMO, G0020, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage: $0 ( -s IP PORT | CMD )" fullword ascii
      $s2 = "os.execl(\"/bin/sh\", \"/bin/sh\", \"-c\", \"$CMD\")" fullword ascii
      $s3 = "PHP_SCRIPT=\"$HOME/public_html/info$X.php\"" fullword ascii
      $s4 = "cat > /dev/tcp/127.0.0.1/80 <<" ascii
   condition: 
      filesize < 15KB and 2 of them
}