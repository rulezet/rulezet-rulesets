rule TTP_XOR_WriteProcessMemory_ee35 {
  strings:
    $key_ee35 = { b9 47 [2] 8b 65 [2] 8d 50 [2] a3 50 [2] 9c 4c }

  condition:
    any of them
}