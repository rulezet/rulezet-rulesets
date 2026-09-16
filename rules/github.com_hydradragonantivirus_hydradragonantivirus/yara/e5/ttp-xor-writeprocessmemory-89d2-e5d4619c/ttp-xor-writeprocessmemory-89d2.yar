rule TTP_XOR_WriteProcessMemory_89d2 {
  strings:
    $key_89d2 = { de a0 [2] ec 82 [2] ea b7 [2] c4 b7 [2] fb ab }

  condition:
    any of them
}