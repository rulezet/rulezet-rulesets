rule TTP_XOR_WriteProcessMemory_a797 {
  strings:
    $key_a797 = { f0 e5 [2] c2 c7 [2] c4 f2 [2] ea f2 [2] d5 ee }

  condition:
    any of them
}