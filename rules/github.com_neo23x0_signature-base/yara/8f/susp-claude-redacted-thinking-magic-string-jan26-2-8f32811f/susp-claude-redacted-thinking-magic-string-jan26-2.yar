rule SUSP_Claude_Redacted_Thinking_Magic_String_Jan26_2 {
   meta:
      description = "Detects Base64 variations of redacted thinking magic string that cause Claude sessions to be terminated. This might indicate that a file tries to prevent being analyzed by LLM agents."
      author = "Marius Benthin"
      date = "2026-01-29"
      reference = "Internal Research"
      score = 75
      id = "453ad61a-838f-529a-b119-1dd3ec559069"
   strings:
      $xb1 = "ANTHROPIC_MAGIC_STRING_TRIGGER_REDACTED_THINKING_" ascii wide base64 base64wide
   condition:
      $xb1
}