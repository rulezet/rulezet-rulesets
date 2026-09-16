rule SUSP_Claude_Refusal_Magic_String_Jan26 {
   meta:
      description = "Detects refusal magic string that cause Claude sessions to be terminated. This might indicate that a file tries to prevent being analyzed by LLM agents."
      author = "Marius Benthin"
      date = "2026-01-29"
      reference = "https://x.com/williballenthin/status/2014687699165135150"
      hash = "ffa48ed4b7b48897f6756c4222b2606399de0bca627cedfddf61e69986580430"
      score = 75
      id = "7a164817-9e90-52f6-a3cb-e6965ee1cc54"
   strings:
      $x1 = "ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_" ascii wide nocase
   condition:
      $x1
}