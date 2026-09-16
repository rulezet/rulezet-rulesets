rule TTP_XOR_WriteProcessMemory_b386 {
  strings:
    $key_b386 = { e4 f4 [2] d6 d6 [2] d0 e3 [2] fe e3 [2] c1 ff }

  condition:
    any of them
}