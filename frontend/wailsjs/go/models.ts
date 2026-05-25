export namespace config {
	
	export class Profile {
	    vault_addr: string;
	    ssh_key_path: string;
	    role: string;
	    ssh_signer_path: string;
	    oidc_mount: string;
	    show_tray: boolean;
	    autostart: boolean;
	    expiry_warn_minutes: number;
	
	    static createFrom(source: any = {}) {
	        return new Profile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.vault_addr = source["vault_addr"];
	        this.ssh_key_path = source["ssh_key_path"];
	        this.role = source["role"];
	        this.ssh_signer_path = source["ssh_signer_path"];
	        this.oidc_mount = source["oidc_mount"];
	        this.show_tray = source["show_tray"];
	        this.autostart = source["autostart"];
	        this.expiry_warn_minutes = source["expiry_warn_minutes"];
	    }
	}
	export class Config {
	    active_profile: string;
	    profiles: Record<string, Profile>;
	    theme: string;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.active_profile = source["active_profile"];
	        this.profiles = this.convertValues(source["profiles"], Profile, true);
	        this.theme = source["theme"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace main {
	
	export class CertDetails {
	    valid: boolean;
	    keyId: string;
	    serial: string;
	    principals: string[];
	    validBefore: string;
	    extensions: string[];
	
	    static createFrom(source: any = {}) {
	        return new CertDetails(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.valid = source["valid"];
	        this.keyId = source["keyId"];
	        this.serial = source["serial"];
	        this.principals = source["principals"];
	        this.validBefore = source["validBefore"];
	        this.extensions = source["extensions"];
	    }
	}
	export class Result {
	    ok: boolean;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ok = source["ok"];
	        this.message = source["message"];
	    }
	}
	export class Status {
	    valid: boolean;
	    displayName: string;
	    ttlSeconds: number;
	    creationTtlSeconds: number;
	    ttlLabel: string;
	    policies: string[];
	    renewable: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.valid = source["valid"];
	        this.displayName = source["displayName"];
	        this.ttlSeconds = source["ttlSeconds"];
	        this.creationTtlSeconds = source["creationTtlSeconds"];
	        this.ttlLabel = source["ttlLabel"];
	        this.policies = source["policies"];
	        this.renewable = source["renewable"];
	    }
	}

}

