rule TTP_XOR_WriteProcessMemory_abaa {
  strings:
    $key_abaa = { fc d8 [2] ce fa [2] c8 cf [2] e6 cf [2] d9 d3 }

  condition:
    any of them
}