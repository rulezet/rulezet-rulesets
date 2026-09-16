rule VULN_Linux_NFS_Exports {
	meta:
		description = "Detects insecure /etc/exports NFS config which might allow privilege escalation to root or other users. The parameter insecure allows any non-root user to mount NFS shares via e.g. an SSH-tunnel. With no_root_squash SUID root binaries are allowed."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://www.errno.fr/nfs_privesc.html"
		author = "Arnim Rupp"
		date = "2022-11-22"
		score = 50
		id = "4b7d81d8-1ae1-5fcf-a91c-271477a839db"
	strings:
				$conf1 = /\n\/.{2,200}?\binsecure\b/ ascii
		$conf2 = /\n\/.{2,200}?\bno_root_squash\b/ ascii

	condition:
		filename == "exports" and 
		filepath contains "/etc" and 
		any of ($conf*)
}