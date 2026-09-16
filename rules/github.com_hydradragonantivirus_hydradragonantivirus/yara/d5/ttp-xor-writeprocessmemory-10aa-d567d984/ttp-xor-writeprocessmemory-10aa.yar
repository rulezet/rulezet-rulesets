rule TTP_XOR_WriteProcessMemory_10aa {
  strings:
    $key_10aa = { 47 d8 [2] 75 fa [2] 73 cf [2] 5d cf [2] 62 d3 }

  condition:
    any of them
}