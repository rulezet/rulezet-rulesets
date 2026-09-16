rule Lazarus_Dec_17_4_RID2CB8 : APT DEMO G0032 NK {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017ithumb.js"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/north-korea-bitten-bitcoin-bug-financially-motivated-campaigns-reveal-new"
      date = "2017-12-20 10:01:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "8ff100ca86cb62117f1290e71d5f9c0519661d6c955d9fcfb71f0bbdf75b51b3"
      hash2 = "7975c09dd436fededd38acee9769ad367bfe07c769770bd152f33a10ed36529e"
      tags = "APT, DEMO, G0032, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "var _0xf5ed=[\"\\x57\\x53\\x63\\x72\\x69\\x70\\x74\\x2E\\x53\\x68\\x65\\x6C\\x6C\"," ascii
   condition: 
      filesize < 9KB and 1 of them
}