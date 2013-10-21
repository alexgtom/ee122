#!/bin/bash

#whois -h xe-0-2-0-1965.inr-341-mulcev.berkeley.edu 136.152.148.1 | grep OrgName
#whois -h t5-5.inr-201-sut.berkeley.edu 128.32.0.84 | grep OrgName
#whois -h xe-4-1-0.inr-001-sut.berkeley.edu 128.32.0.64 | grep OrgName
#whois -h dc-sfo-agg-1--ucb-10ge.cenic.net 137.164.50.16 
#whois -h oak-agg2--sfo-agg1-10g.cenic.net 137.164.22.25 
#whois -h dc-paix-px1--oak-core1-ge.cenic.net 137.164.47.174 
#whois -h hurricane--paix-px1-ge.cenic.net 198.32.251.70 | grep OrgName
#whois -h 10gigabitethernet3-1.core1.sjc2.he.net 72.52.92.70 | grep OrgName
#whois -h 10gigabitethernet14-7.core1.lax2.he.net 184.105.213.5 | grep OrgName
#whois -h 10gigabitethernet2-3.core1.phx2.he.net 184.105.222.85 | grep OrgName
#whois -h 10gigabitethernet5-3.core1.dal1.he.net 184.105.222.78 | grep OrgName
#whois -h 10gigabitethernet5-4.core1.atl1.he.net 184.105.213.114 | grep OrgName
#whois -h 216.66.0.26 216.66.0.26 | grep OrgName

whois -h berkeley.edu 136.152.148.1 | grep OrgName
whois -h berkeley.edu 128.32.0.84 | grep OrgName
whois -h berkeley.edu 128.32.0.64 | grep OrgName
whois -h cenic.net 137.164.50.16 
whois -h cenic.net 137.164.22.25 
whois -h cenic.net 137.164.47.174 
whois -h cenic.net 198.32.251.70 | grep OrgName
whois -h he.net 72.52.92.70 | grep OrgName
whois -h he.net 184.105.213.5 | grep OrgName
whois -h he.net 184.105.222.85 | grep OrgName
whois -h he.net 184.105.222.78 | grep OrgName
whois -h he.net 184.105.213.114 | grep OrgName
whois -h 216.66.0.26 216.66.0.26 | grep OrgName
