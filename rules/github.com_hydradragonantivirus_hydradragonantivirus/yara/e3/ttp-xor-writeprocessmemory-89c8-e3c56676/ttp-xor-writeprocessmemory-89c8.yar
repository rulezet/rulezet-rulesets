rule TTP_XOR_WriteProcessMemory_89c8 {
  strings:
    $key_89c8 = { de ba [2] ec 98 [2] ea ad [2] c4 ad [2] fb b1 }

  condition:
    any of them
}