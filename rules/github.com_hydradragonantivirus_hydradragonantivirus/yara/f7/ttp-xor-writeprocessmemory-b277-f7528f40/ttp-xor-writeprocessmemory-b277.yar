rule TTP_XOR_WriteProcessMemory_b277 {
  strings:
    $key_b277 = { e5 05 [2] d7 27 [2] d1 12 [2] ff 12 [2] c0 0e }

  condition:
    any of them
}