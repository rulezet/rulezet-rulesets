rule EquationGroup_Toolset_Apr17_xxxRIDEAREA_RID359B : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:20:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "214b0de83b04afdd6ad05567825b69663121eda9e804daff9f2da5554ade77c6"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "USAGE: %s -i InputFile -o OutputFile [-f FunctionOrdinal] [-a FunctionArgument] [-t ThreadOption]" fullword ascii
      $x2 = "The output payload \"%s\" has a size of %d-bytes." fullword ascii
      $x3 = "ERROR: fwrite(%s) failed on ucPayload" fullword ascii
      $x4 = "Load and execute implant within the existing thread" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}