rule SUSP_LNK_File_PathTraversal {
   meta:
      description = "Detects a suspicious link file that references a file multiple folders lower than the link itself"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
      date = "2018-05-16"
      score = 40
      id = "f4f6709f-9c4d-5f0c-9826-97444d282adc"
   strings:
      $s1 = "..\\..\\..\\..\\..\\"
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and (
         filesize < 1KB and
         all of them
      )
}