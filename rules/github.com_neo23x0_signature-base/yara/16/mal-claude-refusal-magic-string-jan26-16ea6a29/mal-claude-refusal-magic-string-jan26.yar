rule MAL_Claude_Refusal_Magic_String_Jan26 {
   meta:
      description = "Detects Base64 variations of refusal magic string that cause Claude sessions to be terminated. This might indicate that a file tries to prevent being analyzed by LLM agents."
      author = "Marius Benthin"
      date = "2026-01-29"
      reference = "Internal Research"
      score = 80
      id = "8f0351b7-56b8-5059-8c1e-e8d87fa0ca91"
   strings:
      $xb1 = "ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_" ascii wide base64 base64wide
   condition:
      $xb1
}