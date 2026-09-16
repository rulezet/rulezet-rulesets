rule TTP_XOR_WriteProcessMemory_9ecd {
  strings:
    $key_9ecd = { c9 bf [2] fb 9d [2] fd a8 [2] d3 a8 [2] ec b4 }

  condition:
    any of them
}