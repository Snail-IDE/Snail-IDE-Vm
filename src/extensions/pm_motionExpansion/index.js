// Most of the blocks here are from More Motion by NexusKitten:
// https://scratch.mit.edu/users/NamelessCat/
// https://github.com/NexusKitten

const BlockType = require('../../extension-support/block-type');
const ArgumentType = require('../../extension-support/argument-type');
const Cast = require('../../util/cast');

const blockSeparator = '<sep gap="36"/>'; // At default scale, about 28px

const blocks = `
%block2>
%block3>
${blockSeparator}
<block type="motion_turnrightaroundxy">
    <value name="DEGREES">
        <shadow type="math_number">
            <field name="NUM">15</field>
        </shadow>
    </value>
    <value name="X">
        <shadow type="math_number">
            <field name="NUM">0</field>
        </shadow>
    </value>
    <value name="Y">
        <shadow type="math_number">
            <field name="NUM">0</field>
        </shadow>
    </value>
</block>
<block type="motion_turnleftaroundxy">
    <value name="DEGREES">
        <shadow type="math_number">
            <field name="NUM">15</field>
        </shadow>
    </value>
    <value name="X">
        <shadow type="math_number">
            <field name="NUM">0</field>
        </shadow>
    </value>
    <value name="Y">
        <shadow type="math_number">
            <field name="NUM">0</field>
        </shadow>
    </value>
</block>
<block type="motion_ifonxybounce">
    <value name="X">
        <shadow type="math_number">
            <field name="NUM">10</field>
        </shadow>
    </value>
    <value name="Y">
        <shadow type="math_number">
            <field name="NUM">10</field>
        </shadow>
    </value>
</block>
%block1>
${blockSeparator}
%block0>
%block4>
%block5>
`

/**
 * Class of idk
 * @constructor
 */
class pmMotionExpansion {
    constructor(runtime) {
        /**
         * The runtime instantiating this block package.
         * @type {runtime}
         */
        this.runtime = runtime;
    }

    orderCategoryBlocks(extensionBlocks) {
        if (typeof vm !== "undefined") {
            if (vm.editingTarget) {
                const target = vm.editingTarget;
                if (target.isStage) {
                    return [`<label text="Stage selected: no motion blocks"></label>`];
                }
            }
        }

        let categoryBlocks = blocks;

        let idx = 0;
        for (const block of extensionBlocks) {
            categoryBlocks = categoryBlocks.replace('%block' + idx + '>', block);
            idx++;
        }

        return [categoryBlocks];
    }

    /**
     * @returns {object} metadata for extension category NOT blocks
     * this extension only contains blocks defined elsewhere,
     * since we just want to seperate them rather than create
     * slow versions of them
     */
    getInfo() {
        return {
            id: 'pmMotionExpansion',
            name: 'Motion Expansion',
            color1: '#4C97FF',
            color2: '#4280D7',
            color3: '#3373CC',
            isDynamic: true,
            orderBlocks: this.orderCategoryBlocks,
            blocks: [
                {
                    opcode: "rotationStyle",
                    blockType: BlockType.REPORTER,
                    text: "rotation style",
                    disableMonitor: true,
                },
                {
                    opcode: "fence",
                    blockType: BlockType.COMMAND,
                    text: "manually fence",
                },
                {
                    opcode: "steptowards",
                    blockType: BlockType.COMMAND,
                    text: "move [STEPS] steps towards x: [X] y: [Y]",
                    arguments: {
                        STEPS: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "10",
                        },
                        X: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "0",
                        },
                        Y: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "0",
                        },
                    },
                },
                {
                    opcode: "tweentowards",
                    blockType: BlockType.COMMAND,
                    text: "move [PERCENT]% of the way to x: [X] y: [Y]",
                    arguments: {
                        PERCENT: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "10",
                        },
                        X: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "0",
                        },
                        Y: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "0",
                        },
                    },
                },
                {
                    opcode: "touchingxy",
                    blockType: BlockType.BOOLEAN,
                    text: "touching x: [X] y: [Y]?",
                    arguments: {
                        X: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "0",
                        },
                        Y: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "0",
                        },
                    },
                },
                {
                    opcode: "touchingrect",
                    blockType: BlockType.BOOLEAN,
                    text: "touching rectangle x1: [X1] y1: [Y1] x2: [X2] y2: [Y2]?",
                    arguments: {
                        X1: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "-100",
                        },
                        Y1: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "-100",
                        },
                        X2: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "100",
                        },
                        Y2: {
                            type: ArgumentType.NUMBER,
                            defaultValue: "100",
                        },
                    },
                },
            ]
        };
    }

    rotationStyle(_, util) {
        return util.target.rotationStyle;
    }

    fence(_, util) {
        const newpos = this.runtime.renderer.getFencedPositionOfDrawable(
            util.target.drawableID,
            [util.target.x, util.target.y]
        );
        util.target.setXY(newpos[0], newpos[1]);
    }

    steptowards(args, util) {
        const x = Cast.toNumber(args.X);
        const y = Cast.toNumber(args.Y);
        const steps = Cast.toNumber(args.STEPS);
        const val =
            steps / Math.sqrt((x - util.target.x) ** 2 + (y - util.target.y) ** 2);
        if (val >= 1) {
            util.target.setXY(x, y);
        } else {
            util.target.setXY(
                (x - util.target.x) * val + util.target.x,
                (y - util.target.y) * val + util.target.y
            );
        }
    }

    tweentowards(args, util) {
        const x = Cast.toNumber(args.X);
        const y = Cast.toNumber(args.Y);
        const val = Cast.toNumber(args.PERCENT);
        // Essentially a smooth glide script.
        util.target.setXY(
            (x - util.target.x) * (val / 100) + util.target.x,
            (y - util.target.y) * (val / 100) + util.target.y
        );
    }

    touchingrect(args, util) {
        let left = Cast.toNumber(args.X1);
        let right = Cast.toNumber(args.X2);
        let bottom = Cast.toNumber(args.Y1);
        let top = Cast.toNumber(args.Y2);

        // Fix argument order if they got it backwards
        if (left > right) {
            let temp = left;
            left = right;
            right = temp;
        }
        if (bottom > top) {
            let temp = bottom;
            bottom = top;
            bottom = temp;
        }

        const drawable = this.runtime.renderer._allDrawables[util.target.drawableID];
        if (!drawable) {
            return false;
        }

        // See renderer.isTouchingDrawables

        const drawableBounds = drawable.getFastBounds();
        drawableBounds.snapToInt();

        const Rectangle = this.runtime.renderer.exports.Rectangle;
        const containsBounds = new Rectangle();
        containsBounds.initFromBounds(left, right, bottom, top);
        containsBounds.snapToInt();

        if (!containsBounds.intersects(drawableBounds)) {
            return false;
        }

        drawable.updateCPURenderAttributes();

        const intersectingBounds = Rectangle.intersect(
            drawableBounds,
            containsBounds
        );
        for (let x = intersectingBounds.left; x < intersectingBounds.right; x++) {
            for (
                let y = intersectingBounds.bottom;
                y < intersectingBounds.top;
                y++
            ) {
                // technically should be a twgl vec3, but does not actually need to be
                if (drawable.isTouching([x, y])) {
                    return true;
                }
            }
        }
        return false;
    }

    touchingxy(args, util) {
        const x = Cast.toNumber(args.X);
        const y = Cast.toNumber(args.Y);
        const drawable = this.runtime.renderer._allDrawables[util.target.drawableID];
        if (!drawable) {
            return false;
        }
        // Position should technically be a twgl vec3, but it doesn't actually need to be
        drawable.updateCPURenderAttributes();
        return drawable.isTouching([x, y]);
    }
}

module.exports = pmMotionExpansion;
