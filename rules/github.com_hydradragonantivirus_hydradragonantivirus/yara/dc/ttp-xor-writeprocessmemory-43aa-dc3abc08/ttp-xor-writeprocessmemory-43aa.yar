rule TTP_XOR_WriteProcessMemory_43aa {
  strings:
    $key_43aa = { 14 d8 [2] 26 fa [2] 20 cf [2] 0e cf [2] 31 d3 }

  condition:
    any of them
}