// allow importing data from json files
declare module "*.json" {
    const value: any;
    export default value;
}
