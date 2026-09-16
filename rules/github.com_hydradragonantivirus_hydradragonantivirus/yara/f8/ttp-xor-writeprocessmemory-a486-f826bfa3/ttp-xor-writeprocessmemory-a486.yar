rule TTP_XOR_WriteProcessMemory_a486 {
  strings:
    $key_a486 = { f3 f4 [2] c1 d6 [2] c7 e3 [2] e9 e3 [2] d6 ff }

  condition:
    any of them
}