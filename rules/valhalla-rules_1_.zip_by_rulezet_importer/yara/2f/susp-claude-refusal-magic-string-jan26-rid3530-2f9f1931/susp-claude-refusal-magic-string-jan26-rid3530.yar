rule SUSP_Claude_Refusal_Magic_String_Jan26_RID3530 : DEMO SUSP {
   meta:
      description = "Detects refusal magic string that cause Claude sessions to be terminated. This might indicate that a file tries to prevent being analyzed by LLM agents."
      author = "Marius Benthin"
      reference = "https://x.com/williballenthin/status/2014687699165135150"
      date = "2026-01-29 16:02:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_" ascii wide nocase
   condition: 
      $x1
}