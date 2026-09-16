rule APT_SUSP_NK_3CX_RC4_Key_Mar23_1_RID30E9 : APT DEMO EXE FILE NK SUSP {
   meta:
      description = "Detects RC4 key used in 3CX binaries known to be malicious"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      date = "2023-03-29 13:00:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
      hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
      hash3 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
      tags = "APT, DEMO, EXE, FILE, NK, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "3jB(2bsG#@c7" 
   condition: 
      ( uint16 ( 0 ) == 0xcfd0 or uint16 ( 0 ) == 0x5a4d ) and $x1
}