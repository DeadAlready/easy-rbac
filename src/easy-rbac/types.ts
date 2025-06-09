export type RBACWhen = (input: any) => boolean | Promise<boolean>;

export type RBACCan =
  | string
  | {
      name: string;
      regex?: RegExp | string;
      when: RBACWhen;
    }
  | {
      name: string;
      regex: RegExp | string;
      when?: RBACWhen;
    };

export type RBACRole<Role extends string> = {
  can: RBACCan[];
  inherits?: Role[];
};

export type RBACRoleDefinitions<
  Role extends string,
  InheritRole extends Role
> = {
  [key in Role]: RBACRole<InheritRole>;
};

export type AsyncRoleDefinitions<
  Role extends string,
  InheritRole extends Role
> =
  | Promise<RBACRoleDefinitions<Role, InheritRole>>
  | (() => Promise<RBACRoleDefinitions<Role, InheritRole>>);
