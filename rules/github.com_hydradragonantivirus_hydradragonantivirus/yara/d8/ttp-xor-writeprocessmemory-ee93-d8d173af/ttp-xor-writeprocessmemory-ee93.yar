rule TTP_XOR_WriteProcessMemory_ee93 {
  strings:
    $key_ee93 = { b9 e1 [2] 8b c3 [2] 8d f6 [2] a3 f6 [2] 9c ea }

  condition:
    any of them
}