rule TTP_XOR_WriteProcessMemory_4dee {
  strings:
    $key_4dee = { 1a 9c [2] 28 be [2] 2e 8b [2] 00 8b [2] 3f 97 }

  condition:
    any of them
}