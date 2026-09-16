rule TTP_XOR_WriteProcessMemory_abe5 {
  strings:
    $key_abe5 = { fc 97 [2] ce b5 [2] c8 80 [2] e6 80 [2] d9 9c }

  condition:
    any of them
}