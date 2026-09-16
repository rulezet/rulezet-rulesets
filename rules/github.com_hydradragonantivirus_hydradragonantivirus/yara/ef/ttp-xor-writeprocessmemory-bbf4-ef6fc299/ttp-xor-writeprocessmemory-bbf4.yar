rule TTP_XOR_WriteProcessMemory_bbf4 {
  strings:
    $key_bbf4 = { ec 86 [2] de a4 [2] d8 91 [2] f6 91 [2] c9 8d }

  condition:
    any of them
}