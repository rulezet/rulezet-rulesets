rule TTP_XOR_WriteProcessMemory_9e9f {
  strings:
    $key_9e9f = { c9 ed [2] fb cf [2] fd fa [2] d3 fa [2] ec e6 }

  condition:
    any of them
}