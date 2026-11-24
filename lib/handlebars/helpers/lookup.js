export const dangerousPropertyRegex = /^(constructor|__defineGetter__|__defineSetter__|__lookupGetter__|__lookupSetter__|__proto__)$/;

export default function(instance) {
  instance.registerHelper('lookup', function(obj, field, options) {
    if (!obj) {
      // Note for 5.0: Change to "obj == null" in 5.0
      return obj;
    }
    return options.lookupProperty(obj, field);
  });
}
