import plistlib
import os

pl = plistlib.readPlist("test.plist")

# Validate the plist format

if not pl.has_key("$archiver"):
	print "[-] error: file does not define an $archiver"
	os.exit(1)

if pl["$archiver"] != "NSKeyedArchiver":
	print "[-] error: file was not archived by NSKeyedArchiver"
	os.exit(1)

if not pl.has_key("$version"):
	print "[-] error: file does not define a $version"
	os.exit(1)

if pl["$version"] != 100000:
	print "[-] error: file was archived by unsupported NSKeyedArchiver version"
	os.exit(1)

if not pl.has_key("$top"):
	print "[-] error: file does not define a $top object"
	os.exit(1)

if not pl.has_key("$objects"):
	print "[-] error: file does not contain any objects"
	os.exit(1)

top = int(pl["$top"]["root"]["CF$UID"])
objects = pl["$objects"]

objs = []

for obj in objects:
	objs.append(obj)

print ('digraph {fontsize=40;labelloc=t;'
	'label="CVE-2019-8646";'
	'rankdir=LR; pagedir=BL; clusterrank=local;compound=true;')

nodes = []
edges = []

for i in range(1,len(objs)):

	shape = "box"
	if top == i:
		shape = "diamond"
	if (isinstance(objs[i], plistlib._InternalDict)):
			if objs[i].has_key('$class'):
				c = objs[i]['$class']['CF$UID']

				if not isinstance(objs[c], plistlib._InternalDict):
					print "[-] expected class definition but found"
					print objs[c]
					os.exit(2)
				if not objs[c].has_key("$classname"):
					print "[-] expected class name but found"
					print objs[c]
					os.exit(2)

				c = objs[c]["$classname"]

			else:
				#print objs[i]
				continue

			print "subgraph cluster_%d {label=\"%s\"; rankdir=LR; style=filled; color=lightblue;" % (i, c)
			print "root_%d [shape=point style=invis];" % i

			j = -1
			for k in objs[i].keys():
				if k == '$class':
					continue
				j = j + 1
				print "n_%d_%d;" % (i,j)
				nodes.append("n_%d_%d [fontsize=20; label=\"%s\"; style=filled;color=green; shape=\"box\"];" % (i, j, k) )
				
				val = objs[i][k]
				#print type(val), val
				if isinstance(val, plistlib._InternalDict):
					if val.has_key('CF$UID'):
						idx = int(val['CF$UID'])
						if idx == 0:
							print "d_%d_%d;" % (i,j)
							nodes.append("d_%d_%d [fontsize=20; label=\"null\"; style=filled;color=pink; shape=\"box\"]; "% (i, j))
							edges.append("n_%d_%d -> d_%d_%d;" % (i,j,i,j))
						else:
							if not isinstance(objs[idx], plistlib._InternalDict):
								val = objs[idx]
							else:
								edges.append("n_%d_%d -> root_%d [lhead=cluster_%d];" % (i,j,idx,idx))
				if type(val) == int:
						print "d_%d_%d;" % (i,j)
						nodes.append("d_%d_%d [fontsize=20; label=\"%d\"; style=filled;color=pink; shape=\"box\"]; "% (i, j, val))
						edges.append("n_%d_%d -> d_%d_%d;" % (i,j,i,j))
				elif type(val) == str:
						print "d_%d_%d;" % (i,j)
						nodes.append("d_%d_%d [fontsize=20; label=\"%s\"; style=filled;color=pink; shape=\"box\"]; "% (i, j, val))
						edges.append("n_%d_%d -> d_%d_%d;" % (i,j,i,j))
				elif isinstance(val, plistlib.Data):
						print "d_%d_%d;" % (i,j)
						nodes.append("d_%d_%d [fontsize=20; label=\"%s\"; style=filled;color=pink; shape=\"box\"]; "% (i, j, val))
						edges.append("n_%d_%d -> d_%d_%d;" % (i,j,i,j))
				elif type(val) == list:

						print "subgraph cluster_%d_%d {label=\"\"; rankdir=LR; style=filled; color=orange;" % (i,j)
						print "root_%d_%d [shape=point style=invis];" % (i,j)
						edges.append("n_%d_%d -> root_%d_%d [lhead=cluster_%d_%d];" % (i,j,i,j,i,j))

						vidx = -1
						for v in val:
							vidx = vidx + 1
							print "n_%d_%d_%d;" % (i,j,vidx)
							nodes.append("n_%d_%d_%d [fontsize=20; label=\"%d\"; style=filled;color=yellow; shape=\"box\"]; "% (i, j, vidx, vidx))

							if not isinstance(v, plistlib._InternalDict):
								print "[-] ERROR UNEXPECTED IN ARRAY"
								print type(v),v
								os.exit(2)

							if v.has_key('CF$UID'):
								target = int(v['CF$UID'])
							else:
								print "[-] ERROR UNEXPECTED missing CFUID ARRAY"
								os.exit(2)

							tobj = objs[target]

							if type(tobj) == int:
								vval = str(tobj)
								print "d_%d_%d_%d;" % (i,j,vidx)

								nodes.append("d_%d_%d_%d [fontsize=20; label=\"%s\"; style=filled;color=pink; shape=\"box\"]; "% (i, j, vidx,vval))
								edges.append("n_%d_%d_%d -> d_%d_%d_%d [];" % (i,j,vidx,i,j,vidx))
							elif type(tobj) == str:
								vval = tobj
								print "d_%d_%d_%d;" % (i,j,vidx)

								nodes.append("d_%d_%d_%d [fontsize=20; label=\"%s\"; style=filled;color=pink; shape=\"box\"]; "% (i, j,vidx, vval))
								edges.append("n_%d_%d -> d_%d_%d_%d;" % (i,j,i,j, vidx))
							elif isinstance(val, plistlib.Data):
								vval = tobj
								print "d_%d_%d_%d;" % (i,j,vidx)

								nodes.append("d_%d_%d_%d [fontsize=20; label=\"%s\"; style=filled;color=pink; shape=\"box\"]; "% (i, j,vidx, vval))
								edges.append("n_%d_%d -> d_%d_%d_%d;" % (i,j,i,j, vidx))
							else:
								#print type(tobj),tobj
								edges.append("n_%d_%d_%d -> root_%d [lhead=cluster_%d];" % (i,j,vidx,target,target))
								#nodex.append("d_%d_%d_%d [fontsize=20; label=\"%s\"; style=filled;color=pink; shape=\"box\"];" % (i,j,""))
								#edges.append("n_%d_%d -> d_%d_%d [];" % (i,j,i,j))

							#nodes.append("d_%d_%d [fontsize=20; label=\"%s\"; style=filled;color=pink; shape=\"box\"]; "% (i, j, val))
							#edges.append("n_%d_%d -> d_%d_%d [];" % (i,j,i,j))

						print "}"

				else:
					print
					#print type(val), val

			print "}"
	elif type(objs[i]) == str:
		print
		#print "n_%d [fontsize=20; label=\"%s\"; style=filled;color=green; shape=\"%s\"];" % (i, objs[i], shape)
	elif type(objs[i]) == int:
		print
		#print "n_%d [fontsize=20; label=\"%d\"; style=filled;color=green; shape=\"%s\"];" % (i, objs[i], shape)
	else:
		print ""
		#print type(objs[i]), objs[i]

for n in nodes:
	print n
for e in edges:
	print e

print "}"