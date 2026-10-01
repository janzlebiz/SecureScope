import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { Project, Asset, Scan, Finding, AuditEvent, User, UserRole } from '../../types/securescope';
import { INITIAL_PROJECTS, INITIAL_ASSETS, INITIAL_SCANS, INITIAL_FINDINGS, INITIAL_AUDIT_LOGS } from '../mockData';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DB_FILE = path.resolve(__dirname, '../../../db.json');

export interface DatabaseSchema {
  projects: Project[];
  assets: Asset[];
  scans: Scan[];
  findings: Finding[];
  auditLogs: AuditEvent[];
  users: User[];
}

// Simple local password hashing for demonstration
export function hashPassword(password: string): string {
  return crypto.pbkdf2Sync(password, 'salt-securescope', 1000, 64, 'sha512').toString('hex');
}

// Default Seed Users
const DEFAULT_USERS: User[] = [
  {
    id: 'usr-owner-1',
    name: 'Alex Mercer',
    email: 'alex.mercer@acme-fintech.com',
    role: 'OWNER',
    passwordHash: hashPassword('Password123!'),
    avatarUrl: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80'
  },
  {
    id: 'usr-admin-1',
    name: 'Sarah Chen',
    email: 'sarah.chen@medicare-cloud.org',
    role: 'ADMIN',
    passwordHash: hashPassword('Password123!'),
    avatarUrl: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=100&auto=format&fit=crop&q=80'
  },
  {
    id: 'usr-analyst-1',
    name: 'Frank Castle',
    email: 'analyst@secure.com',
    role: 'ANALYST',
    passwordHash: hashPassword('Password123!'),
    avatarUrl: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=100&auto=format&fit=crop&q=80'
  },
  {
    id: 'usr-viewer-1',
    name: 'Jane Doe',
    email: 'viewer@secure.com',
    role: 'VIEWER',
    passwordHash: hashPassword('Password123!'),
    avatarUrl: 'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?w=100&auto=format&fit=crop&q=80'
  }
];

export class DbStore {
  private static data: DatabaseSchema | null = null;

  private static load() {
    if (this.data) return;

    if (fs.existsSync(DB_FILE)) {
      try {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        this.data = JSON.parse(raw);
        // Ensure users list is populated
        if (!this.data?.users || this.data.users.length === 0) {
          this.data!.users = [...DEFAULT_USERS];
          this.save();
        }
      } catch (err) {
        console.error('[DbStore] Error reading database file, resetting to seeds:', err);
        this.resetToSeeds();
      }
    } else {
      this.resetToSeeds();
    }
  }

  private static resetToSeeds() {
    this.data = {
      projects: JSON.parse(JSON.stringify(INITIAL_PROJECTS)),
      assets: JSON.parse(JSON.stringify(INITIAL_ASSETS)),
      scans: JSON.parse(JSON.stringify(INITIAL_SCANS)),
      findings: JSON.parse(JSON.stringify(INITIAL_FINDINGS)),
      auditLogs: JSON.parse(JSON.stringify(INITIAL_AUDIT_LOGS)),
      users: [...DEFAULT_USERS]
    };
    this.save();
  }

  private static save() {
    if (!this.data) return;
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2), 'utf8');
    } catch (err) {
      console.error('[DbStore] Failed to write database file:', err);
    }
  }

  // --- Projects ---
  public static getProjects(): Project[] {
    this.load();
    return this.data!.projects;
  }

  public static addProject(project: Project) {
    this.load();
    this.data!.projects.unshift(project);
    this.save();
  }

  public static getProjectById(id: string): Project | undefined {
    this.load();
    return this.data!.projects.find(p => p.id === id);
  }

  // --- Assets ---
  public static getAssets(): Asset[] {
    this.load();
    return this.data!.assets;
  }

  public static addAsset(asset: Asset) {
    this.load();
    this.data!.assets.unshift(asset);
    this.save();
  }

  // --- Scans ---
  public static getScans(): Scan[] {
    this.load();
    return this.data!.scans;
  }

  public static addScan(scan: Scan) {
    this.load();
    this.data!.scans.unshift(scan);
    this.save();
  }

  public static updateScan(scan: Scan) {
    this.load();
    const idx = this.data!.scans.findIndex(s => s.id === scan.id);
    if (idx !== -1) {
      this.data!.scans[idx] = scan;
      this.save();
    }
  }

  // --- Findings ---
  public static getFindings(): Finding[] {
    this.load();
    return this.data!.findings;
  }

  public static addFinding(finding: Finding) {
    this.load();
    this.data!.findings.unshift(finding);
    this.save();
  }

  public static updateFinding(finding: Finding) {
    this.load();
    const idx = this.data!.findings.findIndex(f => f.id === finding.id);
    if (idx !== -1) {
      this.data!.findings[idx] = finding;
      this.save();
    }
  }

  // --- Audit Logs ---
  public static getAuditLogs(): AuditEvent[] {
    this.load();
    return this.data!.auditLogs;
  }

  public static addAuditLog(log: AuditEvent) {
    this.load();
    this.data!.auditLogs.unshift(log);
    this.save();
  }

  // --- Users ---
  public static getUsers(): User[] {
    this.load();
    return this.data!.users;
  }

  public static getUserByEmail(email: string): User | undefined {
    this.load();
    return this.data!.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  }

  public static getUserById(id: string): User | undefined {
    this.load();
    return this.data!.users.find(u => u.id === id);
  }
}
