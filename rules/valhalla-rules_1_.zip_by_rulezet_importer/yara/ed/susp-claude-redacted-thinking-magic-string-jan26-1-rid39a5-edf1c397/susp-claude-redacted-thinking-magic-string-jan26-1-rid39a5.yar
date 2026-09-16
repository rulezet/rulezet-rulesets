rule SUSP_Claude_Redacted_Thinking_Magic_String_Jan26_1_RID39A5 : DEMO SUSP {
   meta:
      description = "Detects redacted thinking magic string that cause Claude sessions to be terminated. This might indicate that a file tries to prevent being analyzed by LLM agents."
      author = "Marius Benthin"
      reference = "https://x.com/williballenthin/status/2014687699165135150"
      date = "2026-01-29 19:12:41"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ANTHROPIC_MAGIC_STRING_TRIGGER_REDACTED_THINKING_" ascii wide nocase
   condition: 
      $x1
}