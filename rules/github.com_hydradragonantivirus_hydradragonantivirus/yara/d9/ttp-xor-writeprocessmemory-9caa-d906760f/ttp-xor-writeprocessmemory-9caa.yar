rule TTP_XOR_WriteProcessMemory_9caa {
  strings:
    $key_9caa = { cb d8 [2] f9 fa [2] ff cf [2] d1 cf [2] ee d3 }

  condition:
    any of them
}