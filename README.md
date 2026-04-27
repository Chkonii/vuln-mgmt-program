# Vulnerability Management Program

A hands-on lab program for **detecting, analyzing, and remediating configuration drift** across a small mixed estate (Windows 11, Ubuntu Server, and network-attached assets) against published security baselines. Each workstream follows the same loop: **baseline → induced drift → detection → remediation → verification.**


The shared tooling at the repo root turns raw scanner output into stakeholder-ready artifacts; each platform-specific subfolder contains the data and evidence for its own drift exercise.

# Repository structure

```
vuln-mgmt-program/
├── .venv/                         
├── convertor.py                    
├── README.md                      
├── architecture/                   
│
├── windows11-STIG-Drift/           
│   ├── data/                       
│   ├── breaking/                   
│   ├── drift_analyzer.py           
│   └── README.md
│
├── ubuntu-server-STIG-Drift/       
│
└── network-based-scan/            
    ├── data/
    ├── breaking/
    └── remediation/

verify/                             
```

