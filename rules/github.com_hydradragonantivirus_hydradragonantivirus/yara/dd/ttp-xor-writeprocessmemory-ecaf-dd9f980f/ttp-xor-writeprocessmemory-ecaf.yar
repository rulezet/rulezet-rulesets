rule TTP_XOR_WriteProcessMemory_ecaf {
  strings:
    $key_ecaf = { bb dd [2] 89 ff [2] 8f ca [2] a1 ca [2] 9e d6 }

  condition:
    any of them
}