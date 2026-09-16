rule TTP_XOR_WriteProcessMemory_bbe5 {
  strings:
    $key_bbe5 = { ec 97 [2] de b5 [2] d8 80 [2] f6 80 [2] c9 9c }

  condition:
    any of them
}