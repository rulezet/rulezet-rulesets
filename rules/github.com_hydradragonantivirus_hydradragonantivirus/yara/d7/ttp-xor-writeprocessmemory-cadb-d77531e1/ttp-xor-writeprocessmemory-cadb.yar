rule TTP_XOR_WriteProcessMemory_cadb {
  strings:
    $key_cadb = { 9d a9 [2] af 8b [2] a9 be [2] 87 be [2] b8 a2 }

  condition:
    any of them
}