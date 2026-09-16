rule APT_Bitter_PDB_Paths {
    
    meta:
        description = "Detects Bitter (T-APT-17) PDB Paths"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        tlp = "WHITE"
        reference = "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        date = "2022-06-22"
        hash0 = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

    strings:
                $pdbPath0 = "C:\\Users\\Window 10 C\\Desktop\\COMPLETED WORK\\" ascii
        $pdbPath1 = "stdrcl\\stdrcl\\obj\\Release\\stdrcl.pdb"

                        $pdbPath2 = "g:\\Projects\\cn_stinker_34318\\"
        $pdbPath3 = "renewedstink\\renewedstink\\obj\\Release\\stimulies.pdb"

    condition:
        uint16(0) == 0x5a4d
        and any of ($pdbPath*)
}