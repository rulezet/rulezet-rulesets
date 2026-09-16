rule TTP_XOR_WriteProcessMemory_cf9f {
  strings:
    $key_cf9f = { 98 ed [2] aa cf [2] ac fa [2] 82 fa [2] bd e6 }

  condition:
    any of them
}