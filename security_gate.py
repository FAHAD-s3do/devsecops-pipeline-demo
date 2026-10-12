"""Small educational AST gate, NOT a complete SAST or secret scanner."""
import argparse
import ast
import hashlib
import json
from pathlib import Path


def inspect_source(source):
    tree=ast.parse(source);findings=[]
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call):continue
        name=node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else ''
        if name in ('eval','exec'):
            findings.append(dict(rule='DYNAMIC_EXECUTION',line=node.lineno))
        if name in ('run','Popen','call','check_call','check_output'):
            if any(k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value is True for k in node.keywords):
                findings.append(dict(rule='SHELL_TRUE',line=node.lineno))
    return findings


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('files',nargs='+',type=Path);args=p.parse_args()
    findings=[];artifacts=[]
    try:
        for path in args.files:
            source=path.read_bytes()
            findings.extend(dict(file=str(path),**f) for f in inspect_source(source.decode()))
            artifacts.append(dict(path=str(path),sha256=hashlib.sha256(source).hexdigest()))
    except (OSError,SyntaxError,UnicodeError) as exc:p.exit(2,str(exc)+'\n')
    print(json.dumps(dict(findings=findings,artifacts=artifacts,scope='Explicit source files only; no dependency/CVE/secret scan'),indent=2))
    return int(bool(findings))
if __name__=='__main__':raise SystemExit(main())
