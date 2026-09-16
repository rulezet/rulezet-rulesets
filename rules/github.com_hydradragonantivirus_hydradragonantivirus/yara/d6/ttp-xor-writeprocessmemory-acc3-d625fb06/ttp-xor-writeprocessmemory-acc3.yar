rule TTP_XOR_WriteProcessMemory_acc3 {
  strings:
    $key_acc3 = { fb b1 [2] c9 93 [2] cf a6 [2] e1 a6 [2] de ba }

  condition:
    any of them
}