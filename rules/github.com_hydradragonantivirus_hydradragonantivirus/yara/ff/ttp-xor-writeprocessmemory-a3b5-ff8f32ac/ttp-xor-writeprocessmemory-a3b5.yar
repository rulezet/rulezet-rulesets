rule TTP_XOR_WriteProcessMemory_a3b5 {
  strings:
    $key_a3b5 = { f4 c7 [2] c6 e5 [2] c0 d0 [2] ee d0 [2] d1 cc }

  condition:
    any of them
}