rule TTP_XOR_WriteProcessMemory_bbf5 {
  strings:
    $key_bbf5 = { ec 87 [2] de a5 [2] d8 90 [2] f6 90 [2] c9 8c }

  condition:
    any of them
}