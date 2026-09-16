rule SUSP_Claude_Redacted_Thinking_Magic_String_Jan26_1 {
   meta:
      description = "Detects redacted thinking magic string that cause Claude sessions to be terminated. This might indicate that a file tries to prevent being analyzed by LLM agents."
      author = "Marius Benthin"
      date = "2026-01-29"
      reference = "Internal Research"
      hash = "ffa48ed4b7b48897f6756c4222b2606399de0bca627cedfddf61e69986580430"
      score = 65
      id = "623de3f9-ea03-5b6a-bb24-14b4a6d4a7c9"
   strings:
      $x1 = "ANTHROPIC_MAGIC_STRING_TRIGGER_REDACTED_THINKING_" ascii wide nocase
   condition:
      $x1
}