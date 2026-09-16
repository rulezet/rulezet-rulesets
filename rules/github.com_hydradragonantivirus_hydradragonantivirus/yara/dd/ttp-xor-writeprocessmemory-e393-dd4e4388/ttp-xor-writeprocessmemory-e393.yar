rule TTP_XOR_WriteProcessMemory_e393 {
  strings:
    $key_e393 = { b4 e1 [2] 86 c3 [2] 80 f6 [2] ae f6 [2] 91 ea }

  condition:
    any of them
}