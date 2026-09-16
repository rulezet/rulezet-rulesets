rule TTP_XOR_WriteProcessMemory_89d9 {
  strings:
    $key_89d9 = { de ab [2] ec 89 [2] ea bc [2] c4 bc [2] fb a0 }

  condition:
    any of them
}